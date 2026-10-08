//! Guarded open: warrant Subpath intersected with the executor jail.
#![cfg(unix)]

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tenuo::constraints::Subpath;
use tenuo::sdk::{
    Containment, FilesystemError, GuardError, Guarded, LocalSigner, OpenOptions,
    PresentedAuthority, RevocationMode, Runtime, Workspace,
};
use tenuo::{
    args, constraints, Authorizer, Call, ConstraintSet, Guard, Pattern, SigningKey, Warrant,
};

struct Layout {
    local: tempfile::TempDir,
}

fn layout() -> Layout {
    let local = tempfile::tempdir().expect("local");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::create_dir(local.path().join("reports")).expect("reports");
    std::fs::write(local.path().join("reports/q4.md"), b"quarterly").expect("q4");
    std::fs::write(local.path().join("secrets.txt"), b"secret").expect("secrets");
    std::fs::write(outside.path().join("secret"), b"outside").expect("outside");
    std::os::unix::fs::symlink(outside.path().join("secret"), local.path().join("link"))
        .expect("symlink");
    Layout { local }
}

fn harness(
    local: &Path,
    constraints: ConstraintSet,
    containment: Containment,
) -> (Guard, PresentedAuthority) {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability("read_file", constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .expect("warrant");
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let workspace = Workspace::new("/workspace", local, containment).expect("workspace");
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .filesystem(workspace)
        .build()
        .expect("guard");
    let authority = PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder)))
        .expect("authority");
    (guard, authority)
}

fn read_at(
    guard: &Guard,
    authority: &PresentedAuthority,
    path: &str,
) -> Result<String, GuardError<FilesystemError>> {
    let call = Call::owned("read_file", args! { "path" => path }).expect("call");
    guard
        .guard(authority, &call, |authorized| {
            let mut file = authorized.open("path", OpenOptions::read_only())?;
            let mut body = String::new();
            file.read_to_string(&mut body).expect("read");
            Ok(body)
        })
        .map(Guarded::into_inner)
}

#[test]
fn reads_the_authorized_file_under_the_local_root() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let body = read_at(&guard, &authority, "/workspace/reports/q4.md").expect("open");
    assert_eq!(body, "quarterly");
}

#[test]
fn best_effort_reports_platform_toctou() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let call = Call::owned("read_file", args! { "path" => "/workspace/reports/q4.md" }).unwrap();
    let guarded = guard
        .guard(&authority, &call, |authorized| {
            authorized.open("path", OpenOptions::read_only())
        })
        .expect("open");
    let file = guarded.into_inner();
    let linux_atomic = cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ));
    assert_eq!(file.toctou_safe(), linux_atomic);
}

#[test]
fn atomic_fails_closed_off_the_kernel_path() {
    let layout = layout();
    let linux_atomic = cfg!(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ));
    let built = Workspace::new("/workspace", layout.local.path(), Containment::Atomic);
    if linux_atomic {
        assert!(built.is_ok());
    } else {
        assert!(matches!(
            built.err(),
            Some(FilesystemError::AtomicUnavailable)
        ));
    }
}

#[test]
fn symlink_escape_is_rejected() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let err = read_at(&guard, &authority, "/workspace/link").expect_err("symlink");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::NotTheNamedFile)
    ));
    let shown = format!("{err} {err:?}");
    let host = layout.local.path().to_string_lossy();
    assert!(!shown.contains(host.as_ref()), "{shown}");
}

#[test]
fn traversal_never_opens() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let call = Call::owned("read_file", args! { "path" => "/workspace/../etc/passwd" }).unwrap();
    assert!(guard.check(&authority, &call).is_err());
}

#[test]
fn prefix_sibling_is_denied() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let call = Call::owned("read_file", args! { "path" => "/workspace-evil/q4.md" }).unwrap();
    assert!(guard.check(&authority, &call).is_err());
}

#[test]
fn wider_warrant_than_ceiling_is_denied_at_open() {
    let layout = layout();
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability(
            "read_file",
            constraints! { "path" => Subpath::new("/workspace").unwrap() },
        )
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let workspace = Workspace::new(
        "/workspace/reports",
        layout.local.path().join("reports"),
        Containment::BestEffort,
    )
    .unwrap();
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .filesystem(workspace)
        .build()
        .unwrap();
    let authority =
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
    let err = read_at(&guard, &authority, "/workspace/reports/q4.md").expect_err("ceiling");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::WarrantOutsideCeiling)
    ));
}

#[test]
fn narrowed_leaf_opens_when_the_parent_root_is_wider_than_the_ceiling() {
    let layout = layout();
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let parent = Warrant::builder()
        .capability(
            "read_file",
            constraints! { "path" => Subpath::new("/workspace").unwrap() },
        )
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .unwrap();
    let child = parent
        .attenuate()
        .holder(holder.public_key())
        .tool(
            "read_file",
            constraints! { "path" => Subpath::new("/workspace/reports").unwrap() },
        )
        .ttl(Duration::from_secs(60))
        .build(&holder)
        .unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let workspace = Workspace::new(
        "/workspace/reports",
        layout.local.path().join("reports"),
        Containment::BestEffort,
    )
    .unwrap();
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .filesystem(workspace)
        .build()
        .unwrap();
    let authority =
        PresentedAuthority::new(vec![parent, child], Arc::new(LocalSigner::new(holder))).unwrap();
    let body = read_at(&guard, &authority, "/workspace/reports/q4.md").expect("leaf open");
    assert_eq!(body, "quarterly");
}

#[test]
fn pattern_constraint_does_not_open() {
    let layout = layout();
    std::fs::write(layout.local.path().join("q4.md"), b"top").unwrap();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Pattern::new("/workspace/*").unwrap() },
        Containment::BestEffort,
    );
    let err = read_at(&guard, &authority, "/workspace/q4.md").expect_err("pattern");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::NotASubpath { .. })
    ));
}

#[test]
fn missing_workspace_fails_closed() {
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability(
            "read_file",
            constraints! { "path" => Subpath::new("/workspace").unwrap() },
        )
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .build()
        .unwrap();
    let authority =
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();
    let err = read_at(&guard, &authority, "/workspace/reports/q4.md").expect_err("no jail");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::WorkspaceMissing)
    ));
}

#[test]
fn open_uses_the_named_argument() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let call = Call::owned("read_file", args! { "path" => "/workspace/reports/q4.md" }).unwrap();
    let opened = guard.guard(&authority, &call, |authorized| {
        authorized.open("file", OpenOptions::read_only())
    });
    assert!(matches!(
        opened,
        Err(GuardError::Operation(
            FilesystemError::UnknownArgument { .. }
        ))
    ));
}

#[test]
fn write_and_create_stay_inside_the_jail() {
    let layout = layout();
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let mut constraints = ConstraintSet::new();
    constraints.insert("path", Subpath::new("/workspace").unwrap());
    let warrant = Warrant::builder()
        .capability("write_file", constraints.clone())
        .capability("create_file", constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let workspace =
        Workspace::new("/workspace", layout.local.path(), Containment::BestEffort).unwrap();
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .filesystem(workspace)
        .build()
        .unwrap();
    let authority =
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();

    let write = Call::owned("write_file", args! { "path" => "/workspace/reports/q4.md" }).unwrap();
    let _written = guard
        .guard(&authority, &write, |authorized| {
            let mut file = authorized.open("path", OpenOptions::write_truncate())?;
            file.write_all(b"updated").expect("write");
            Ok::<_, FilesystemError>(())
        })
        .expect("write");
    assert_eq!(
        std::fs::read(layout.local.path().join("reports/q4.md")).unwrap(),
        b"updated"
    );

    let create = Call::owned(
        "create_file",
        args! { "path" => "/workspace/reports/new.md" },
    )
    .unwrap();
    let _created = guard
        .guard(&authority, &create, |authorized| {
            let mut file = authorized.open("path", OpenOptions::create_new())?;
            file.write_all(b"created").expect("create");
            Ok::<_, FilesystemError>(())
        })
        .expect("create");
    assert_eq!(
        std::fs::read(layout.local.path().join("reports/new.md")).unwrap(),
        b"created"
    );
}

#[test]
fn logical_filesystem_root_is_rejected() {
    let layout = layout();
    let err = Workspace::new("/", layout.local.path(), Containment::BestEffort).unwrap_err();
    assert!(matches!(err, FilesystemError::LogicalRootIsFilesystemRoot));
}

#[test]
fn session_carries_the_workspace() {
    let layout = layout();
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let warrant = Warrant::builder()
        .capability(
            "read_file",
            constraints! { "path" => Subpath::new("/workspace").unwrap() },
        )
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .unwrap();
    let runtime = Runtime::builder()
        .holder(holder)
        .trusted_root(issuer.public_key())
        .ttl_fallback(Duration::from_secs(3600))
        .build()
        .unwrap();
    let workspace =
        Workspace::new("/workspace", layout.local.path(), Containment::BestEffort).unwrap();
    let session = runtime
        .session_from_warrant(warrant)
        .unwrap()
        .with_filesystem(workspace);
    let call = Call::owned("read_file", args! { "path" => "/workspace/reports/q4.md" }).unwrap();
    let body = session
        .guard(&call, |authorized| {
            let mut file = authorized
                .open("path", OpenOptions::read_only())
                .map_err(std::io::Error::other)?;
            let mut body = String::new();
            file.read_to_string(&mut body)?;
            Ok::<_, std::io::Error>(body)
        })
        .expect("session")
        .into_inner();
    assert_eq!(body, "quarterly");
}

#[test]
fn case_insensitive_subpath_does_not_open() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! {
            "path" => Subpath::with_options("/workspace", false, true).unwrap()
        },
        Containment::BestEffort,
    );
    let err = read_at(&guard, &authority, "/workspace/reports/q4.md").expect_err("case");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::CaseInsensitive { .. })
    ));
}

#[test]
fn symlink_inside_a_narrow_leaf_does_not_read_the_parent() {
    let layout = layout();
    std::os::unix::fs::symlink(
        layout.local.path().join("secrets.txt"),
        layout.local.path().join("reports/leak"),
    )
    .expect("symlink");
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace/reports").unwrap() },
        Containment::BestEffort,
    );
    let err = read_at(&guard, &authority, "/workspace/reports/leak").expect_err("leaf symlink");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::NotTheNamedFile)
    ));
    assert_eq!(
        std::fs::read(layout.local.path().join("secrets.txt")).unwrap(),
        b"secret"
    );

    let write = Call::owned("read_file", args! { "path" => "/workspace/reports/leak" }).unwrap();
    let truncated = guard.guard(&authority, &write, |authorized| {
        authorized.open("path", OpenOptions::write_truncate())
    });
    assert!(matches!(
        truncated,
        Err(GuardError::Operation(FilesystemError::NotTheNamedFile))
    ));
    assert_eq!(
        std::fs::read(layout.local.path().join("secrets.txt")).unwrap(),
        b"secret"
    );
}

#[test]
fn case_folded_name_does_not_open_another_entry() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let err = read_at(&guard, &authority, "/workspace/reports/Q4.md").expect_err("case");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::NotFound)
            | GuardError::Operation(FilesystemError::NotTheNamedFile)
    ));
    assert_eq!(
        std::fs::read(layout.local.path().join("reports/q4.md")).unwrap(),
        b"quarterly"
    );
}

#[test]
fn empty_open_options_do_not_read() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let call = Call::owned("read_file", args! { "path" => "/workspace/reports/q4.md" }).unwrap();
    let err = guard
        .guard(&authority, &call, |authorized| {
            authorized.open("path", OpenOptions::new())
        })
        .expect_err("no access mode");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::AccessModeMissing)
    ));
}

#[test]
fn raced_directory_symlink_does_not_return_outside_bytes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let layout = layout();
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("file"), b"OUTSIDE-RACE").expect("outside");
    let gate = layout.local.path().join("gate");
    let hold = layout.local.path().join("gate-hold");
    std::fs::create_dir(&gate).expect("gate");
    std::fs::write(gate.join("file"), b"INSIDE").expect("inside");
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flip = Arc::clone(&stop);
    let gate_flip = gate.clone();
    let hold_flip = hold.clone();
    let outside_dir = outside.path().to_path_buf();
    let flipper = std::thread::spawn(move || {
        while !stop_flip.load(Ordering::Relaxed) {
            if std::fs::rename(&gate_flip, &hold_flip).is_ok() {
                if std::os::unix::fs::symlink(&outside_dir, &gate_flip).is_ok() {
                    std::thread::yield_now();
                    let _ = std::fs::remove_file(&gate_flip);
                }
                if gate_flip.exists() {
                    let _ = std::fs::remove_file(&gate_flip);
                }
                let _ = std::fs::rename(&hold_flip, &gate_flip);
            } else {
                let _ = std::fs::remove_file(&gate_flip);
                let _ = std::fs::rename(&hold_flip, &gate_flip);
            }
        }
    });
    for _ in 0..200 {
        if let Ok(body) = read_at(&guard, &authority, "/workspace/gate/file") {
            assert_ne!(body, "OUTSIDE-RACE", "raced open returned the outside file");
        }
    }
    stop.store(true, Ordering::Relaxed);
    flipper.join().expect("flipper");
}

#[test]
fn directory_is_not_a_regular_file() {
    let layout = layout();
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let err = read_at(&guard, &authority, "/workspace/reports").expect_err("directory");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::NotRegularFile)
    ));
}

#[test]
fn hard_link_is_rejected_without_truncating() {
    let layout = layout();
    std::fs::hard_link(
        layout.local.path().join("reports/q4.md"),
        layout.local.path().join("reports/q4-link.md"),
    )
    .expect("hard link");
    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let constraints = constraints! { "path" => Subpath::new("/workspace").unwrap() };
    let warrant = Warrant::builder()
        .capability("read_file", constraints.clone())
        .capability("write_file", constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)
        .unwrap();
    let mut authorizer = Authorizer::new();
    authorizer.add_trusted_root(issuer.public_key());
    let workspace =
        Workspace::new("/workspace", layout.local.path(), Containment::BestEffort).unwrap();
    let guard = Guard::builder()
        .authorizer(authorizer)
        .revocation(RevocationMode::TtlOnly {
            max_lifetime: Duration::from_secs(3600),
        })
        .filesystem(workspace)
        .build()
        .unwrap();
    let authority =
        PresentedAuthority::new(vec![warrant], Arc::new(LocalSigner::new(holder))).unwrap();

    let err = read_at(&guard, &authority, "/workspace/reports/q4-link.md").expect_err("link");
    assert!(matches!(
        err,
        GuardError::Operation(FilesystemError::HardLinkRejected)
    ));

    let write = Call::owned("write_file", args! { "path" => "/workspace/reports/q4.md" }).unwrap();
    let truncated = guard.guard(&authority, &write, |authorized| {
        authorized.open("path", OpenOptions::write_truncate())
    });
    assert!(matches!(
        truncated,
        Err(GuardError::Operation(FilesystemError::HardLinkRejected))
    ));
    assert_eq!(
        std::fs::read(layout.local.path().join("reports/q4.md")).unwrap(),
        b"quarterly"
    );
}

#[test]
fn hard_link_check_can_be_turned_off() {
    let layout = layout();
    std::fs::hard_link(
        layout.local.path().join("reports/q4.md"),
        layout.local.path().join("reports/q4-link.md"),
    )
    .expect("hard link");
    let (guard, authority) = harness(
        layout.local.path(),
        constraints! { "path" => Subpath::new("/workspace").unwrap() },
        Containment::BestEffort,
    );
    let call = Call::owned(
        "read_file",
        args! { "path" => "/workspace/reports/q4-link.md" },
    )
    .unwrap();
    let file = guard
        .guard(&authority, &call, |authorized| {
            authorized.open(
                "path",
                OpenOptions::read_only()
                    .reject_hard_links(false)
                    .require_regular_file(false),
            )
        })
        .expect("open")
        .into_inner();
    assert!(file.has_hard_links());
}
