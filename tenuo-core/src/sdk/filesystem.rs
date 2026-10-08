//! Open a file the guard just authorized.
//!
//! [`Subpath`] stays lexical. It does not look at the machine where the file
//! will be opened. This module is the execution step: after [`Guard::guard`]
//! allows a call, [`AuthorizedCall::open`] takes one argument **name**, maps
//! that authorized logical path under the executor's jail, and returns a file
//! descriptor. The caller does not pass a second path.
//!
//! The jail root is executor configuration, attached with
//! [`Session::with_filesystem`] or [`Guard::with_filesystem`]. A warrant cannot
//! choose it. A warrant [`Subpath`] wider than the configured logical root is
//! denied, including when the parent warrant is wider and the leaf has been
//! narrowed underneath.
//!
//! `atomic` fails at construction where the platform cannot give
//! `openat2(RESOLVE_BENEATH)`. `best-effort` uses the platform fallback and
//! reports that on [`OpenedFile::toctou_safe`].
//!
//! [`OpenOptions`] rejects a non-regular file and a file with extra hard links
//! unless the caller turns those checks off. Symlinks are always rejected.
//! Where the kernel enforces the open, that relative path is the open. On the
//! fallback, the opened handle is checked against the named directory entry,
//! and `create` / `create_new` are refused because a raced parent symlink can
//! leave a file behind. Truncate runs only after that check.
//!
//! ```no_run
//! # #[cfg(unix)]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::io::Read;
//! use std::time::Duration;
//! use tenuo::sdk::{Containment, OpenOptions, Runtime, Workspace};
//! use tenuo::constraints::Subpath;
//! use tenuo::{args, Call, ConstraintSet, SigningKey, Warrant};
//!
//! let issuer = SigningKey::generate();
//! let holder = SigningKey::generate();
//! let mut constraints = ConstraintSet::new();
//! constraints.insert("path", Subpath::new("/workspace")?);
//! let warrant = Warrant::builder()
//!     .capability("read_file", constraints)
//!     .holder(holder.public_key())
//!     .ttl(Duration::from_secs(60))
//!     .build(&issuer)?;
//!
//! let runtime = Runtime::builder()
//!     .holder(holder)
//!     .trusted_root(issuer.public_key())
//!     .ttl_fallback(Duration::from_secs(120))
//!     .build()?;
//! let workspace = Workspace::new("/workspace", "/srv/jobs/job-1842", Containment::Atomic)?;
//! let session = runtime
//!     .session_from_warrant(warrant)?
//!     .with_filesystem(workspace);
//!
//! let call = Call::owned("read_file", args! { "path" => "/workspace/reports/q4.md" })?;
//! let guarded = session.guard(&call, |authorized| {
//!     let mut file = authorized
//!         .open("path", OpenOptions::read_only())
//!         .map_err(std::io::Error::other)?;
//!     let mut body = String::new();
//!     file.read_to_string(&mut body)?;
//!     Ok::<_, std::io::Error>(body)
//! })?;
//! let _body = guarded.into_inner();
//! # Ok(())
//! # }
//! # #[cfg(not(unix))]
//! # fn main() {}
//! ```
//!
//! [`Subpath`]: crate::Subpath
//! [`Guard::guard`]: crate::sdk::Guard::guard
//! [`AuthorizedCall::open`]: crate::sdk::AuthorizedCall::open
//! [`Session::with_filesystem`]: crate::sdk::Session::with_filesystem
//! [`Guard::with_filesystem`]: crate::sdk::Guard::with_filesystem
//! [`OpenedFile::toctou_safe`]: OpenedFile::toctou_safe

use std::collections::HashMap;
use std::fmt;
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

#[cfg(unix)]
use std::io::{Read, Seek, Write};

use crate::constraints::{Constraint, ConstraintValue, Subpath};
use crate::warrant::Warrant;
use crate::Error;

#[cfg(unix)]
use path_jail::guard::OpenOptions as JailOpenOptions;
#[cfg(unix)]
use path_jail::guard::{FdJail, GuardedFile};
#[cfg(unix)]
use path_jail::JailError;

/// How strictly an open must be kernel-enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Containment {
    /// Fail unless the open is TOCTOU-safe (`openat2` with `RESOLVE_BENEATH`).
    ///
    /// Construction fails on platforms where [`path_jail`](https://github.com/tenuo-ai/path_jail)
    /// can only offer the final-component fallback.
    Atomic,
    /// Use the platform fallback. [`OpenedFile::toctou_safe`] is `false` there.
    ///
    /// macOS, BSD, and Linux architectures other than x86_64 and aarch64 open
    /// with `O_NOFOLLOW` on the final component. Linux x86_64 and aarch64 do
    /// not fall back: if `openat2` is missing or blocked, [`Workspace::new`]
    /// fails. `create` and `create_new` are refused on the fallback.
    BestEffort,
}

/// Access a [`Workspace::limit_capability`] allows for one capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityAccess {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
}

impl CapabilityAccess {
    /// Read an existing file. Write, append, truncate, and create are refused.
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            append: false,
            truncate: false,
            create: false,
        }
    }

    /// Read, write, append, truncate, and create.
    ///
    /// Create is still refused where the open is not kernel-enforced.
    pub fn write() -> Self {
        Self {
            read: true,
            write: true,
            append: true,
            truncate: true,
            create: true,
        }
    }

    fn permits(&self, options: &OpenOptions) -> bool {
        (!options.read || self.read)
            && (!options.write || self.write)
            && (!options.append || self.append)
            && (!options.truncate || self.truncate)
            && (!(options.create || options.create_new) || self.create)
    }
}

/// Executor ceiling and pinned local jail.
///
/// `logical_root` is the path warrants speak. `local_root` is the directory on
/// this machine that stands in for it. The two are not the same string: a job
/// whose warrant says `/workspace/reports/q4.md` may be mounted at
/// `/srv/jobs/job-1842`.
pub struct Workspace {
    logical: Subpath,
    containment: Containment,
    limits: HashMap<String, CapabilityAccess>,
    #[cfg(unix)]
    jail: FdJail,
}

impl fmt::Debug for Workspace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Workspace")
            .field("logical_root", &self.logical.root)
            .field("containment", &self.containment)
            .finish_non_exhaustive()
    }
}

impl Workspace {
    /// Pin `local_root` and record the logical ceiling.
    ///
    /// `logical_root` must be absolute and must not be the filesystem root.
    /// `local_root` must be an existing directory. [`Containment::Atomic`]
    /// fails where the kernel guarantee is unavailable. On Linux x86_64 and
    /// aarch64 both modes fail when `openat2` is missing or blocked, because
    /// that architecture has no fallback.
    pub fn new(
        logical_root: impl AsRef<str>,
        local_root: impl AsRef<Path>,
        containment: Containment,
    ) -> Result<Self, FilesystemError> {
        let logical = Subpath::new(logical_root.as_ref()).map_err(FilesystemError::Policy)?;
        if logical.root == "/" {
            return Err(FilesystemError::LogicalRootIsFilesystemRoot);
        }
        #[cfg(not(unix))]
        {
            let _ = (local_root, containment);
            return Err(FilesystemError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            if !atomic_platform() && containment == Containment::Atomic {
                return Err(FilesystemError::AtomicUnavailable);
            }
            let jail =
                FdJail::new(local_root.as_ref()).map_err(|err| map_jail_new(err, containment))?;
            Ok(Self {
                logical,
                containment,
                limits: HashMap::new(),
                jail,
            })
        }
    }

    /// Restrict `capability` to `access`.
    ///
    /// Without a limit, the handler's [`OpenOptions`] decide. A limit makes a
    /// `read_file` handler fail closed when it asks to write or create.
    pub fn limit_capability(
        mut self,
        capability: impl Into<String>,
        access: CapabilityAccess,
    ) -> Self {
        self.limits.insert(capability.into(), access);
        self
    }

    pub(crate) fn open_authorized(
        &self,
        argument: &str,
        capability: &str,
        execution_args: &HashMap<String, ConstraintValue>,
        chain: &[Warrant],
        options: &OpenOptions,
    ) -> Result<OpenedFile, FilesystemError> {
        let path =
            execution_args
                .get(argument)
                .ok_or_else(|| FilesystemError::UnknownArgument {
                    name: argument.to_string(),
                })?;
        let path = path
            .as_str()
            .ok_or_else(|| FilesystemError::ArgumentNotString {
                name: argument.to_string(),
            })?;
        let constraint = leaf_constraint(chain, capability, argument)?;
        let effective = effective_subpath(constraint, path, argument)?;
        if !self
            .logical
            .contains_path(&effective.root)
            .map_err(FilesystemError::Policy)?
        {
            return Err(FilesystemError::WarrantOutsideCeiling);
        }
        if !self
            .logical
            .contains_path(path)
            .map_err(FilesystemError::Policy)?
        {
            return Err(FilesystemError::PathOutsideCeiling);
        }
        let relative = self
            .logical
            .lexical_remainder(path)
            .map_err(FilesystemError::Policy)?
            .ok_or(FilesystemError::PathOutsideCeiling)?;
        if !relative_is_file(&relative) {
            return Err(FilesystemError::EmptyRelativePath);
        }
        options.validate()?;
        if let Some(allowed) = self.limits.get(capability) {
            if !allowed.permits(options) {
                return Err(FilesystemError::AccessNotPermitted {
                    name: capability.to_string(),
                });
            }
        }

        #[cfg(not(unix))]
        {
            return Err(FilesystemError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            if (options.create || options.create_new) && !atomic_platform() {
                return Err(FilesystemError::CreateRequiresAtomic);
            }
            reject_symlink_entries(self.jail.root(), &relative)?;
            let opened = self
                .jail
                .open(&relative, options.to_jail())
                .map_err(map_open)?;
            if self.containment == Containment::Atomic && !opened.attestation().toctou_safe {
                return Err(FilesystemError::AtomicUnavailable);
            }
            // `openat2` already opened this relative path with symlinks rejected.
            // Reading `/proc` there is not the enforcement, and some containers
            // do not mount it. The fallback still has to check the handle.
            if !opened.attestation().toctou_safe {
                match named_entry(self.jail.root(), &relative, &opened) {
                    NamedEntry::Match => {}
                    NamedEntry::Mismatch => return Err(FilesystemError::NotTheNamedFile),
                    NamedEntry::Unavailable => {
                        return Err(FilesystemError::EntryCheckUnavailable);
                    }
                }
            }
            if options.truncate {
                opened
                    .file()
                    .set_len(0)
                    .map_err(|_| FilesystemError::OpenFailed)?;
            }
            Ok(OpenedFile { file: opened })
        }
    }
}

fn relative_is_file(relative: &str) -> bool {
    !relative.is_empty()
        && !relative.starts_with('/')
        && relative
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

fn leaf_constraint<'a>(
    chain: &'a [Warrant],
    capability: &str,
    argument: &str,
) -> Result<&'a Constraint, FilesystemError> {
    let leaf = chain.last().ok_or_else(|| FilesystemError::NotASubpath {
        name: argument.to_string(),
    })?;
    let tools = leaf
        .capabilities()
        .ok_or_else(|| FilesystemError::NotASubpath {
            name: argument.to_string(),
        })?;
    let set = tools
        .get(capability)
        .ok_or_else(|| FilesystemError::NotASubpath {
            name: argument.to_string(),
        })?;
    set.get(argument)
        .ok_or_else(|| FilesystemError::NotASubpath {
            name: argument.to_string(),
        })
}

/// Subpath roots that actually cover `path`.
///
/// `Any` contributes only branches that match. `Not` contributes nothing: a
/// negated root is not a jail. The narrowest covering root is the one the
/// open is bounded by.
fn effective_subpath<'a>(
    constraint: &'a Constraint,
    path: &str,
    argument: &str,
) -> Result<&'a Subpath, FilesystemError> {
    let mut found = Vec::new();
    collect_covering(constraint, path, &mut found)?;
    if found.is_empty() {
        return Err(FilesystemError::NotASubpath {
            name: argument.to_string(),
        });
    }
    if found.iter().any(|subpath| !subpath.case_sensitive) {
        return Err(FilesystemError::CaseInsensitive {
            name: argument.to_string(),
        });
    }
    select_narrowest(&found)
}

fn collect_covering<'a>(
    constraint: &'a Constraint,
    path: &str,
    out: &mut Vec<&'a Subpath>,
) -> Result<(), FilesystemError> {
    let value = ConstraintValue::String(path.to_string());
    match constraint {
        Constraint::Subpath(subpath) => {
            if subpath
                .contains_path(path)
                .map_err(FilesystemError::Policy)?
            {
                out.push(subpath);
            }
            Ok(())
        }
        Constraint::All(all) => {
            for child in &all.constraints {
                collect_covering(child, path, out)?;
            }
            Ok(())
        }
        Constraint::Any(any) => {
            for child in &any.constraints {
                if child.matches(&value).map_err(FilesystemError::Policy)? {
                    collect_covering(child, path, out)?;
                }
            }
            Ok(())
        }
        Constraint::Not(_) => Ok(()),
        _ => Ok(()),
    }
}

fn select_narrowest<'a>(roots: &[&'a Subpath]) -> Result<&'a Subpath, FilesystemError> {
    let mut best = roots[0];
    for candidate in roots.iter().copied().skip(1) {
        if candidate.root == best.root {
            continue;
        }
        let best_holds = best
            .contains_path(&candidate.root)
            .map_err(FilesystemError::Policy)?;
        let candidate_holds = candidate
            .contains_path(&best.root)
            .map_err(FilesystemError::Policy)?;
        if best_holds {
            best = candidate;
        } else if !candidate_holds {
            return Err(FilesystemError::AmbiguousRoot);
        }
    }
    for candidate in roots {
        if candidate.root != best.root
            && !candidate
                .contains_path(&best.root)
                .map_err(FilesystemError::Policy)?
        {
            return Err(FilesystemError::AmbiguousRoot);
        }
    }
    Ok(best)
}

#[cfg(unix)]
fn atomic_platform() -> bool {
    cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))
}

#[cfg(unix)]
fn map_open(err: JailError) -> FilesystemError {
    match err {
        JailError::FileTypeRejected { .. } => FilesystemError::NotRegularFile,
        JailError::HardLinkRejected { .. } => FilesystemError::HardLinkRejected,
        JailError::Io(err) => map_io(err),
        JailError::Escape { .. } | JailError::EscapedRoot { .. } => FilesystemError::EscapedJail,
        JailError::SymlinkRejected { .. } | JailError::BrokenSymlink(_) => {
            FilesystemError::NotTheNamedFile
        }
        _ => FilesystemError::OpenFailed,
    }
}

#[cfg(unix)]
fn map_io(err: std::io::Error) -> FilesystemError {
    match err.kind() {
        std::io::ErrorKind::NotFound => FilesystemError::NotFound,
        std::io::ErrorKind::AlreadyExists => FilesystemError::AlreadyExists,
        std::io::ErrorKind::PermissionDenied => FilesystemError::PermissionDenied,
        _ => FilesystemError::OpenFailed,
    }
}

/// Reject a symlink anywhere in `relative` before `open` follows it.
///
/// The final component may be missing. An existing symlink is not the named
/// file, and opening it can truncate the target.
#[cfg(unix)]
fn reject_symlink_entries(root: &Path, relative: &str) -> Result<(), FilesystemError> {
    let mut current = root.to_path_buf();
    let parts: Vec<&str> = relative.split('/').collect();
    for (index, component) in parts.iter().enumerate() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(FilesystemError::NotTheNamedFile);
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if index + 1 == parts.len() {
                    return Ok(());
                }
                return Err(FilesystemError::NotFound);
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(FilesystemError::PermissionDenied);
            }
            Err(_) => return Err(FilesystemError::OpenFailed),
        }
    }
    Ok(())
}

#[cfg(unix)]
enum NamedEntry {
    Match,
    Mismatch,
    Unavailable,
}

/// The opened handle's path is `root/relative`, byte for byte.
///
/// Used on the fallback, where the kernel did not enforce the open. A missing
/// path lookup is [`NamedEntry::Unavailable`], not a claim that the file is
/// the wrong entry. The host path is not returned.
#[cfg(unix)]
fn named_entry(root: &Path, relative: &str, opened: &GuardedFile) -> NamedEntry {
    let Ok(actual) = fd_path(opened.file()) else {
        return NamedEntry::Unavailable;
    };
    use std::os::unix::ffi::OsStrExt;
    let root_bytes = root.as_os_str().as_bytes();
    let actual_bytes = actual.as_os_str().as_bytes();
    let Some(rest) = actual_bytes.strip_prefix(root_bytes) else {
        return NamedEntry::Mismatch;
    };
    let Some(rest) = rest.strip_prefix(b"/") else {
        return NamedEntry::Mismatch;
    };
    if rest == relative.as_bytes() {
        NamedEntry::Match
    } else {
        NamedEntry::Mismatch
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn fd_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(all(unix, target_os = "macos"))]
fn fd_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;
    extern "C" {
        fn fcntl(fd: std::os::raw::c_int, cmd: std::os::raw::c_int, ...) -> std::os::raw::c_int;
    }
    // `F_GETPATH` from `<fcntl.h>`: write the vnode's path into `buf`.
    const F_GETPATH: std::os::raw::c_int = 50;
    let mut buf = [0u8; 1024];
    // SAFETY: `file` owns `fd` for this call. `buf` is writable for 1024 bytes.
    // `F_GETPATH` writes a NUL-terminated path and does not retain the pointer.
    let rc = unsafe { fcntl(file.as_raw_fd(), F_GETPATH, buf.as_mut_ptr()) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let len = buf
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| std::io::Error::other("fd path was not returned"))?;
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..len])))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn fd_path(file: &std::fs::File) -> std::io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    std::fs::read_link(format!("/dev/fd/{}", file.as_raw_fd()))
}

#[cfg(unix)]
fn map_jail_new(err: JailError, containment: Containment) -> FilesystemError {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    if matches!(err, JailError::UnsupportedKernel { .. }) {
        return FilesystemError::KernelJailUnavailable;
    }
    let _ = (err, containment);
    FilesystemError::InvalidJailRoot
}

/// Flags for [`AuthorizedCall::open`](crate::sdk::AuthorizedCall::open).
///
/// The warrant already decided the tool may run. These flags are how that
/// tool opens the authorized argument. `read_file` and `write_file` stay
/// separate capabilities; this type does not promote one into the other.
///
/// A new value requires a regular file and rejects extra hard links. Both
/// checks use `fstat` on the opened handle. Turn them off only when the tool
/// is meant to see another file type or to decide about hard links itself.
/// Symlinks are rejected on every open. [`Workspace::limit_capability`] is how
/// a `read_file` capability refuses [`Self::write_truncate`]. Without a limit,
/// the handler's flags are the access mode.
///
/// `no_xdev` starts off. Linux maps it to `RESOLVE_NO_XDEV`. The fallback does
/// not enforce it. A mount crossing that the kernel reports is
/// [`FilesystemError::EscapedJail`].
#[derive(Debug, Clone)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    require_regular_file: bool,
    reject_hard_links: bool,
    no_xdev: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            require_regular_file: true,
            reject_hard_links: true,
            no_xdev: false,
        }
    }
}

impl OpenOptions {
    /// Handle policies at their defaults, with no read, write, or append.
    ///
    /// An open with no access mode is rejected. This does not read the file.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read an existing file.
    pub fn read_only() -> Self {
        Self::new().read(true)
    }

    /// Write an existing file, truncating it.
    pub fn write_truncate() -> Self {
        Self::new().write(true).truncate(true)
    }

    /// Create a file that must not already exist.
    pub fn create_new() -> Self {
        Self {
            write: true,
            create_new: true,
            ..Self::new()
        }
    }

    /// Set read access.
    pub fn read(mut self, yes: bool) -> Self {
        self.read = yes;
        self
    }

    /// Set write access.
    pub fn write(mut self, yes: bool) -> Self {
        self.write = yes;
        self
    }

    /// Set append mode.
    pub fn append(mut self, yes: bool) -> Self {
        self.append = yes;
        self
    }

    /// Truncate the file on open. Requires write.
    pub fn truncate(mut self, yes: bool) -> Self {
        self.truncate = yes;
        self
    }

    /// Create the file if it is missing. Requires write or append.
    pub fn create(mut self, yes: bool) -> Self {
        self.create = yes;
        self
    }

    /// Reject a handle that is not a regular file.
    ///
    /// On by default. A directory, FIFO, or other non-regular file that yields
    /// a handle fails with [`FilesystemError::NotRegularFile`], and the handle
    /// is closed. A socket, or a write-only FIFO with no reader, fails in the
    /// kernel before a handle exists and is [`FilesystemError::OpenFailed`].
    pub fn require_regular_file(mut self, yes: bool) -> Self {
        self.require_regular_file = yes;
        self
    }

    /// Reject a file with more than one hard link.
    ///
    /// On by default. When this is set with [`truncate`](Self::truncate), the
    /// file is truncated only after the link count is checked, so an already
    /// hard-linked file is not emptied.
    pub fn reject_hard_links(mut self, yes: bool) -> Self {
        self.reject_hard_links = yes;
        self
    }

    /// Reject an open that crosses a mount point.
    ///
    /// Off by default. Linux maps this to `RESOLVE_NO_XDEV`. The platform
    /// fallback does not enforce it.
    pub fn no_xdev(mut self, yes: bool) -> Self {
        self.no_xdev = yes;
        self
    }

    #[cfg(unix)]
    fn to_jail(&self) -> JailOpenOptions {
        JailOpenOptions::new()
            .read(self.read)
            .write(self.write)
            .append(self.append)
            .truncate(false)
            .create(self.create)
            .create_new(self.create_new)
            .require_regular_file(self.require_regular_file)
            .reject_hard_links(self.reject_hard_links)
            .no_symlinks(true)
            .no_xdev(self.no_xdev)
    }

    fn validate(&self) -> Result<(), FilesystemError> {
        if !self.read && !self.write && !self.append {
            return Err(FilesystemError::AccessModeMissing);
        }
        let can_write = self.write || self.append;
        if (self.create || self.create_new) && !can_write {
            return Err(FilesystemError::InvalidOpenOptions);
        }
        if self.truncate && !self.write {
            return Err(FilesystemError::InvalidOpenOptions);
        }
        if self.truncate && self.append {
            return Err(FilesystemError::InvalidOpenOptions);
        }
        Ok(())
    }
}

/// File opened beneath the executor jail.
///
/// The value is the descriptor. It does not expose a path.
pub struct OpenedFile {
    #[cfg(unix)]
    file: GuardedFile,
}

impl fmt::Debug for OpenedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedFile")
            .field("toctou_safe", &self.toctou_safe())
            .finish_non_exhaustive()
    }
}

impl OpenedFile {
    /// `true` when this open used `openat2(RESOLVE_BENEATH)`.
    pub fn toctou_safe(&self) -> bool {
        #[cfg(unix)]
        {
            self.file.attestation().toctou_safe
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// `true` when the opened file has more than one hard link.
    ///
    /// The default open rejects that file before it is returned. This is for a
    /// caller that turned [`OpenOptions::reject_hard_links`] off.
    pub fn has_hard_links(&self) -> bool {
        #[cfg(unix)]
        {
            self.file.has_hard_links()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// Release the descriptor. The returned file still has no path.
    #[cfg(unix)]
    pub fn into_std(self) -> std::fs::File {
        self.file.into_file()
    }
}

#[cfg(unix)]
impl Read for OpenedFile {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf)
    }
}

#[cfg(unix)]
impl Write for OpenedFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(unix)]
impl Seek for OpenedFile {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        self.file.seek(pos)
    }
}

#[cfg(unix)]
impl std::os::unix::io::AsFd for OpenedFile {
    fn as_fd(&self) -> std::os::unix::io::BorrowedFd<'_> {
        std::os::unix::io::AsFd::as_fd(&self.file)
    }
}

/// Failure to map an authorized argument into the local jail, or to open it.
#[derive(Debug)]
#[non_exhaustive]
pub enum FilesystemError {
    /// The guard has no workspace.
    WorkspaceMissing,
    /// This platform has no `path_jail` guard open.
    UnsupportedPlatform,
    /// `atomic` was requested and the open would not be TOCTOU-safe.
    AtomicUnavailable,
    /// The logical ceiling is `/`.
    LogicalRootIsFilesystemRoot,
    /// `argument` is not on the authorized call.
    UnknownArgument {
        /// Argument name passed to `open`.
        name: String,
    },
    /// The authorized argument is not a string.
    ArgumentNotString {
        /// Argument name passed to `open`.
        name: String,
    },
    /// The leaf warrant does not bound this argument with [`Subpath`].
    ///
    /// [`Subpath`]: crate::Subpath
    NotASubpath {
        /// Argument name passed to `open`.
        name: String,
    },
    /// A case-insensitive [`Subpath`] cannot choose the bytes the kernel opens.
    ///
    /// [`Subpath`]: crate::Subpath
    CaseInsensitive {
        /// Argument name passed to `open`.
        name: String,
    },
    /// The leaf [`Subpath`] root is outside the executor logical ceiling.
    ///
    /// [`Subpath`]: crate::Subpath
    WarrantOutsideCeiling,
    /// The authorized path is outside the executor logical ceiling.
    PathOutsideCeiling,
    /// More than one covering [`Subpath`] and neither contains the other.
    ///
    /// [`Subpath`]: crate::Subpath
    AmbiguousRoot,
    /// The authorized path is the logical root, so there is no file beneath it.
    EmptyRelativePath,
    /// The opened handle is not a regular file.
    NotRegularFile,
    /// The opened file has more than one hard link.
    HardLinkRejected,
    /// The capability's [`CapabilityAccess`] does not allow these flags.
    AccessNotPermitted {
        /// Capability name on the call.
        name: String,
    },
    /// `create` or `create_new` was requested where the open is not kernel-enforced.
    ///
    /// A raced parent symlink on that fallback can create the file outside the
    /// jail before the handle is rejected. Truncate is separate: it runs only
    /// after the opened handle is checked.
    CreateRequiresAtomic,
    /// `openat2` is missing or blocked, so this architecture cannot pin a jail.
    ///
    /// Linux x86_64 and aarch64 have no `O_NOFOLLOW` fallback. macOS and BSD
    /// do not return this error; they use [`Containment::BestEffort`].
    KernelJailUnavailable,
    /// The fallback could not read the opened handle's path.
    ///
    /// The file was not returned. This is not evidence that the path was wrong.
    EntryCheckUnavailable,
    /// The path leaves the jail, including a mount crossing when `no_xdev` is set.
    EscapedJail,
    /// The operating system denied access to the named file.
    PermissionDenied,
    /// The open has no read, write, or append access.
    AccessModeMissing,
    /// The flag combination cannot be applied.
    InvalidOpenOptions,
    /// The authorized file does not exist.
    NotFound,
    /// The authorized file already exists.
    AlreadyExists,
    /// The local directory could not be pinned.
    InvalidJailRoot,
    /// The opened handle is not the named directory entry.
    ///
    /// This covers a symlink, a case-folded name for another file, and an open
    /// that raced onto a different file. The host path is not included.
    NotTheNamedFile,
    /// The open was rejected.
    OpenFailed,
    /// Lexical [`Subpath`] check failed.
    ///
    /// [`Subpath`]: crate::Subpath
    Policy(Error),
}

impl fmt::Display for FilesystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkspaceMissing => write!(f, "guard has no filesystem workspace"),
            Self::UnsupportedPlatform => {
                write!(f, "filesystem open is unavailable on this platform")
            }
            Self::AtomicUnavailable => {
                write!(f, "atomic containment is unavailable on this platform")
            }
            Self::LogicalRootIsFilesystemRoot => {
                write!(f, "logical root must not be the filesystem root")
            }
            Self::UnknownArgument { name } => {
                write!(f, "authorized call has no argument {name}")
            }
            Self::ArgumentNotString { name } => {
                write!(f, "authorized argument {name} is not a string")
            }
            Self::NotASubpath { name } => {
                write!(f, "authorized argument {name} is not bounded by Subpath")
            }
            Self::CaseInsensitive { name } => {
                write!(
                    f,
                    "authorized argument {name} uses a case-insensitive Subpath"
                )
            }
            Self::WarrantOutsideCeiling => {
                write!(f, "warrant root is outside the executor logical root")
            }
            Self::PathOutsideCeiling => {
                write!(f, "authorized path is outside the executor logical root")
            }
            Self::AmbiguousRoot => write!(f, "warrant Subpath roots do not nest"),
            Self::EmptyRelativePath => {
                write!(f, "authorized path is the logical root and names no file")
            }
            Self::NotRegularFile => write!(f, "opened handle is not a regular file"),
            Self::HardLinkRejected => {
                write!(f, "opened file has more than one hard link")
            }
            Self::AccessNotPermitted { name } => {
                write!(f, "capability {name} does not allow this open")
            }
            Self::CreateRequiresAtomic => {
                write!(f, "creating a file requires kernel-enforced containment")
            }
            Self::KernelJailUnavailable => {
                write!(f, "openat2 is unavailable, so this host cannot pin a jail")
            }
            Self::EntryCheckUnavailable => {
                write!(f, "could not confirm the opened file's directory entry")
            }
            Self::EscapedJail => write!(f, "the path leaves the jail"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::AccessModeMissing => write!(f, "open needs read, write, or append"),
            Self::InvalidOpenOptions => write!(f, "open flags are not a valid combination"),
            Self::NotFound => write!(f, "authorized file does not exist"),
            Self::AlreadyExists => write!(f, "authorized file already exists"),
            Self::InvalidJailRoot => write!(f, "local jail root could not be pinned"),
            Self::NotTheNamedFile => {
                write!(f, "opened file is not the named directory entry")
            }
            Self::OpenFailed => write!(f, "open was rejected"),
            Self::Policy(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for FilesystemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(err) => Some(err),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constraints::{Any, Constraint};

    fn sub(root: &str) -> Subpath {
        Subpath::new(root).expect("root")
    }

    #[test]
    fn narrowest_matching_branch_wins() {
        let reports = sub("/workspace/reports");
        let other = sub("/other");
        let constraint = Constraint::Any(Any::new([
            Constraint::Subpath(reports),
            Constraint::Subpath(other),
        ]));
        let chosen =
            effective_subpath(&constraint, "/workspace/reports/q4.md", "path").expect("root");
        assert_eq!(chosen.root, "/workspace/reports");
    }

    #[test]
    fn pattern_without_subpath_is_not_a_jail() {
        let constraint = Constraint::Pattern(crate::Pattern::new("/workspace/*").expect("glob"));
        let err = effective_subpath(&constraint, "/workspace/q4.md", "path").expect_err("deny");
        assert!(matches!(err, FilesystemError::NotASubpath { .. }));
    }

    #[test]
    fn all_keeps_the_narrower_root() {
        let constraint = Constraint::All(crate::constraints::All::new([
            Constraint::Subpath(sub("/workspace")),
            Constraint::Subpath(sub("/workspace/reports")),
        ]));
        let chosen =
            effective_subpath(&constraint, "/workspace/reports/q4.md", "path").expect("root");
        assert_eq!(chosen.root, "/workspace/reports");
    }

    #[test]
    fn remainder_strips_the_logical_prefix() {
        let ceiling = sub("/workspace");
        assert_eq!(
            ceiling
                .lexical_remainder("/workspace/reports/q4.md")
                .expect("remainder")
                .as_deref(),
            Some("reports/q4.md")
        );
        assert_eq!(
            ceiling
                .lexical_remainder("/workspace-evil/q4.md")
                .expect("remainder")
                .as_deref(),
            None
        );
    }
}
